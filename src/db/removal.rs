//! Event removal operations: NIP-09 deletions, NIP-86 bans, NIP-62
//! vanish and the NIP-40 expiration purge.

use std::sync::Arc;

use super::db_error;
#[cfg(test)]
use super::store::take_chunk_fault;
use super::store::{
    CREATED_LEN, GIFT_WRAP_INDEX, ID_LEN, Store, created_key, decode_pending_purge,
    decode_purged_group_marker, delegated_by, deleted_address_key, dtag_key_safe,
    encode_pending_deletion, encode_pending_purge, encode_purged_group_marker, is_group_state_kind,
    pending_deletion_key, pubkey_key, purged_group_key, replaceable_key, tag_key,
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

/// The partial outcome of a chunked removal walk: what was removed before
/// the walk ended, whether the removed events feed the derived NIP-29 /
/// NIP-43 state, and the failure that stopped it (if any). The counters
/// stay meaningful when `error` is `Some`: a later chunk that failed must
/// not hide the state events an earlier chunk already removed (the derived
/// state still needs the rebuild), nor the events it already removed.
pub(crate) struct RemovalReport {
    pub removed: usize,
    pub group_state_removed: bool,
    pub error: Option<anyhow::Error>,
}

impl RemovalReport {
    /// Whether the walk completed cleanly.
    pub(crate) fn is_clean(&self) -> bool {
        self.error.is_none()
    }

    /// The removed count for a successful walk, `None` on failure: the
    /// checked callers must not report a partial removal as a clean one.
    pub(crate) fn checked_removed(&self) -> Option<usize> {
        self.is_clean().then_some(self.removed)
    }
}

/// Compares two hex pubkeys/ids on decoded bytes (case-insensitive like
/// the scan's hex decode), falling back to exact match when either side
/// is not valid hex.
fn pubkeys_equal(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
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
    ) -> RemovalReport {
        let mut removed = 0usize;
        let mut group_state_removed = false;
        let error = self
            .apply_deletion_walk(
                targets,
                addresses,
                request_pubkey,
                request_created,
                group,
                &mut removed,
                &mut group_state_removed,
            )
            .err();
        RemovalReport {
            removed,
            group_state_removed,
            error,
        }
    }

    /// The chunked walk behind [`Self::apply_deletion_group`]. Records the
    /// request in [`DELETE_PENDING`] before the first removal chunk and
    /// clears it only after every chunk committed: an error mid-walk (or a
    /// shutdown cancellation) leaves the record for the startup resume. The
    /// out-parameters carry the partial counters to the caller's report.
    #[allow(clippy::too_many_arguments)]
    fn apply_deletion_walk(
        &self,
        targets: &[String],
        addresses: &[nip09::Address],
        request_pubkey: Option<&str>,
        request_created: u64,
        group: Option<&str>,
        removed: &mut usize,
        group_state_removed: &mut bool,
    ) -> Result<()> {
        // Disk-full guard: a removal still writes (the deleted marker),
        // so the same SIGBUS protection as the put path applies.
        self.disk_full_error()?;
        // Fail closed: a deletion must be scoped to a requester (author /
        // delegator) or to a group. The old signature allowed both to be
        // `None`, which skipped every authorization check and would delete
        // arbitrary events if a future caller passed neither.
        if request_pubkey.is_none() && group.is_none() {
            return Ok(());
        }
        // Record the request before the first removal chunk. A request with
        // nothing to walk (no tags) cannot be interrupted, so it writes no
        // record that would need clearing.
        let pending_encoded =
            encode_pending_deletion(targets, addresses, request_pubkey, request_created, group);
        let pending_key = pending_deletion_key(&pending_encoded);
        let has_work = !targets.is_empty() || !addresses.is_empty();
        if has_work {
            self.put_pending_deletion(&pending_key, &pending_encoded)?;
        }

        // The `e`-tag targets are bounded by the deletion request's own tag
        // list, but the batch is still split into REMOVAL_CHUNK-sized write
        // transactions so a huge request never pins one commit.
        for chunk in targets.chunks(REMOVAL_CHUNK) {
            if self.cancelled() {
                // A SIGTERM mid-walk stops at the chunk boundary: the
                // pending record stays and the next startup resumes the
                // walk (fail-closed). Reporting the partial removal here
                // is not needed — the record is the durable statement.
                return Err(anyhow::anyhow!(
                    "NIP-09 deletion cancelled during shutdown; resuming at next startup"
                ));
            }
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            let mut wtxn = self.env.write_txn()?;
            let mut chunk_state_removed = false;
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
                // The derived NIP-29/NIP-43 state is built from these kinds
                // (see `is_group_state_kind`): the stamp must advance in the
                // same removal transaction, or a crash after this commit
                // could restore a snapshot that still authorizes the
                // deleted grant.
                chunk_state_removed |= is_group_state_kind(event.kind);
                self.remove_event(&mut wtxn, &id)?;
                *removed += 1;
            }
            if chunk_state_removed {
                self.bump_state_stamp(&mut wtxn)?;
            }
            wtxn.commit()?;
            *group_state_removed |= chunk_state_removed;
            // Test-only: fail after the chunk committed, so the resume
            // path runs over a genuinely partial walk.
            #[cfg(test)]
            if self
                .fail_next_delete_chunk
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::anyhow!("test-only delete chunk failure"));
            }
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
                if self.cancelled() {
                    return Err(anyhow::anyhow!(
                        "NIP-09 deletion cancelled during shutdown; resuming at next startup"
                    ));
                }
                #[cfg(test)]
                if take_chunk_fault(&self.fail_chunk_after) {
                    return Err(anyhow::anyhow!("test-only removal chunk failure"));
                }
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
                let mut chunk_state_removed = false;
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
                    // Every slot under this range is keyed by `address.kind`
                    // (the walk only filters pubkey/d), so its kind decides
                    // whether the derived state must be invalidated. Bumped
                    // in the same transaction as the removal (see the
                    // `e`-tag path).
                    chunk_state_removed |= is_group_state_kind(address.kind);
                    self.remove_event(&mut wtxn, id)?;
                    *removed += 1;
                }
                if chunk_state_removed {
                    self.bump_state_stamp(&mut wtxn)?;
                }
                wtxn.commit()?;
                *group_state_removed |= chunk_state_removed;
                // See the `e`-tag walk: fail after a committed chunk so the
                // resume runs over a partial removal.
                #[cfg(test)]
                if self
                    .fail_next_delete_chunk
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(anyhow::anyhow!("test-only delete chunk failure"));
                }
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

        // The whole walk committed cleanly: the request no longer needs a
        // resume record. A failed clear leaves the record, and the next
        // startup replays the (idempotent) walk.
        if has_work {
            self.clear_pending_deletion(&pending_key)?;
        }
        Ok(())
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
    /// window where re-published events are accepted.
    ///
    /// The same commit records the purge in [`PURGE_PENDING`]: a crash or
    /// `MapFull` after the marker but before the walk completes would
    /// otherwise leave a ghosted group whose marker rejects every event —
    /// including a re-issued `kind:9008` — while the old history stays
    /// stored. [`Self::pending_purges`] reports the record so the caller
    /// re-issues the purge, which is idempotent and keeps the furthest cut.
    /// The completion commit folds the newest removed timestamp into the
    /// cut, clears the in-progress record and bumps the derived-state stamp.
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
            self.purge_pending
                .put(&mut wtxn, &key, &encode_pending_purge(gid, purge_now, cut))?;
            wtxn.commit()?;
            (purge_now, cut)
        };
        let start = tag_key(b'h', gid.as_bytes(), 0, &[0u8; ID_LEN]);
        let end = tag_key(b'h', gid.as_bytes(), u64::MAX, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        let mut removed = 0usize;
        let mut max_created = 0u64;
        loop {
            if self.cancelled() {
                // SIGTERM mid-walk: stop at the chunk boundary and leave the
                // pending record (written above) for the next startup.
                return Err(anyhow::anyhow!(
                    "NIP-29 group purge cancelled during shutdown; resuming at next startup"
                ));
            }
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            // Test-only: fail after the marker and in-progress record
            // committed, so the resume path runs with real crash state.
            #[cfg(test)]
            if self
                .fail_next_purge_chunk
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::anyhow!("test-only purge chunk failure"));
            }
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
        // Completion commit: re-merge the marker (a legacy 8-byte marker was
        // upgraded by the initial commit above), clear the in-progress
        // record and bump the derived-state stamp in one transaction. The
        // stamp bump always happens here: every purge removes (or confirms
        // the absence of) group history, and the derived state must be
        // rebuilt from the surviving events.
        let mut wtxn = self.env.write_txn()?;
        let (old_now, old_cut) = self
            .purged_groups
            .get(&wtxn, &key)?
            .map(decode_purged_group_marker)
            .unwrap_or((0, 0));
        purge_now = purge_now.max(old_now);
        cut = cut.max(old_cut).max(max_created);
        self.purged_groups
            .put(&mut wtxn, &key, &encode_purged_group_marker(purge_now, cut))?;
        self.purge_pending.delete(&mut wtxn, &key)?;
        self.bump_state_stamp(&mut wtxn)?;
        wtxn.commit()?;
        Ok(removed)
    }

    /// Started-but-unfinished group purges as `(gid, purge_now)`: each was
    /// recorded before its first removal chunk and not cleared, so the
    /// caller re-runs `purge_group(gid, purge_now)` to finish it (the walk
    /// is idempotent and the marker keeps the furthest cut). A malformed
    /// record is an error, so a caller that fails closed never treats a
    /// corrupt pending table as "nothing to resume".
    pub(crate) fn pending_purges(&self) -> Result<Vec<(String, u64)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.purge_pending.iter(&rtxn)? {
            let (_, raw) = item?;
            let (gid, purge_now, _) = decode_pending_purge(raw).ok_or_else(|| {
                anyhow::anyhow!("corrupt pending purge record ({} bytes)", raw.len())
            })?;
            out.push((gid, purge_now));
        }
        Ok(out)
    }

    /// NIP-62: deletes every event authored by `pubkey` (including NIP-09
    /// deletion requests and NIP-59 gift wraps that p-tag it) and records the
    /// pubkey so that no future event from it is accepted.
    ///
    /// Replays are cheap: the stored marker keeps the furthest `until_created`
    /// already honored, and a request covered by it removes nothing (NIP-62
    /// requests are signed, re-broadcastable events, so an unchecked replay
    /// would re-walk the author's whole history and rewrite the NIP-29/43
    /// snapshots on every delivery). Only the *completed* marker
    /// short-circuits: an in-progress record means the walk was interrupted
    /// and must be retried.
    pub(crate) fn apply_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<(usize, bool)> {
        self.disk_full_error()?;
        // Replay check: a completed marker covering this request means every
        // event up to its cut was already removed, so there is nothing to do.
        {
            let rtxn = self.env.read_txn()?;
            // Legacy entries (written before the marker carried the timestamp)
            // have an empty value and count as `until_created = 0`, so they are
            // upgraded by the next request.
            if self
                .vanished_until(&rtxn, pubkey)?
                .is_some_and(|covered| covered >= until_created)
            {
                return Ok((0, false));
            }
        }
        // Persist the in-progress record *before* the first removal chunk:
        // a crash or a store error mid-walk is then resumed at startup (or
        // by a re-delivered request) instead of leaving removed events with
        // no marker and no cursor. The merged cut is returned so a
        // re-delivered older request never walks a shorter bound than the
        // interrupted one.
        let until_created = self.record_pending_vanish(pubkey, until_created)?;
        self.finish_vanish(pubkey, until_created)
    }

    /// Completes every interrupted vanish before the writer serves its first
    /// message (called from the writer thread at startup, so no put can
    /// interleave and no `DbClient` round trip is needed — which would
    /// deadlock the writer against itself). Idempotent: already-removed
    /// events are simply not found, and a crash between the marker and the
    /// pending clear re-writes the same (furthest) marker. A failed record
    /// is logged and left in place for the next restart or re-delivery.
    pub(crate) fn resume_pending_vanishes(
        &self,
        errors: &Arc<std::sync::atomic::AtomicU64>,
    ) -> usize {
        let pending = match self.pending_vanishes() {
            Ok(pending) => pending,
            Err(e) => {
                db_error(errors, &e);
                return 0;
            }
        };
        let mut completed = 0usize;
        for (pubkey, until_created) in pending {
            match self.finish_vanish(&pubkey, until_created) {
                Ok(_) => completed += 1,
                Err(e) => db_error(errors, &e),
            }
        }
        completed
    }

    /// Completes every interrupted NIP-09 deletion before the writer serves
    /// its first message (same startup/atomicity reasoning as
    /// [`Self::resume_pending_vanishes`]). Each record is replayed through
    /// the ordinary (idempotent) walk, which re-records and, on a clean
    /// completion, clears it. The returned flag is true when any resumed
    /// deletion removed a NIP-29/NIP-43 state event: the relay must mark
    /// the derived state stale (the persistent state stamp is bumped in the
    /// same removal transactions, and this flag surfaces the fact directly
    /// to the startup path).
    pub(crate) fn resume_pending_deletions(
        &self,
        errors: &Arc<std::sync::atomic::AtomicU64>,
    ) -> (usize, bool) {
        let pending = match self.pending_deletions() {
            Ok(pending) => pending,
            Err(e) => {
                db_error(errors, &e);
                return (0, false);
            }
        };
        let mut completed = 0usize;
        let mut group_state_removed = false;
        for request in pending {
            if self.cancelled() {
                break;
            }
            // A record with neither a requester nor a group scope can never
            // authorize a removal (the walk refuses it): drop it so it does
            // not block every startup forever. Legitimate records always
            // carry one of the two.
            if request.request_pubkey.is_none() && request.group.is_none() {
                let encoded = encode_pending_deletion(
                    &request.targets,
                    &request.addresses,
                    None,
                    request.request_created,
                    None,
                );
                if let Err(e) = self.clear_pending_deletion(&pending_deletion_key(&encoded)) {
                    db_error(errors, &e);
                }
                continue;
            }
            let report = self.apply_deletion_group(
                &request.targets,
                &request.addresses,
                request.request_pubkey.as_deref(),
                request.request_created,
                request.group.as_deref(),
            );
            group_state_removed |= report.group_state_removed;
            match report.error {
                Some(e) => db_error(errors, &e),
                None => completed += 1,
            }
        }
        (completed, group_state_removed)
    }

    /// Every started-but-unfinished vanish as `(pubkey, until_created)`,
    /// used by the startup resume. A malformed record (bitrot) is skipped
    /// with a warning: the completed-marker path still fails closed for the
    /// pubkey once its marker exists, and a skipped record must not abort
    /// the resume of the healthy ones.
    pub(crate) fn pending_vanishes(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.vanish_pending.iter(&rtxn)? {
            let (key, raw) = item?;
            match raw.get(..8) {
                Some(bytes) => out.push((
                    key.to_vec(),
                    u64::from_be_bytes(bytes.try_into().expect("checked length")),
                )),
                None => log::warn!(
                    "skipping corrupt pending vanish record ({} bytes)",
                    raw.len()
                ),
            }
        }
        Ok(out)
    }

    /// The completed vanish bound for `pubkey`, if any (see [`VANISH`]).
    fn vanished_until(&self, rtxn: &heed::RoTxn, pubkey: &[u8]) -> Result<Option<u64>> {
        Ok(self
            .vanish
            .get(rtxn, pubkey)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length"))))
    }

    /// Persists the in-progress vanish record (pubkey -> furthest
    /// `until_created`) and returns the merged bound, so a re-delivered
    /// older request resumes the interrupted one's full cut.
    fn record_pending_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<u64> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let until = self
            .vanish_pending
            .get(&wtxn, pubkey)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
            .unwrap_or(0)
            .max(until_created);
        self.vanish_pending
            .put(&mut wtxn, pubkey, &until.to_be_bytes())?;
        wtxn.commit()?;
        Ok(until)
    }

    /// Walks and removes `pubkey`'s history up to `until_created`, drops the
    /// addressed gift wraps, then writes the completed marker and clears the
    /// pending record in the same commit. The walk is idempotent, so both a
    /// re-delivered request and the startup resume can call it. The
    /// derived-state stamp is bumped inside each chunk's transaction that
    /// removed a NIP-29/NIP-43 state event, so a crash later in the walk
    /// cannot lose the fact that the derived state changed.
    fn finish_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<(usize, bool)> {
        // The resume path enters here directly: refuse to write to a full
        // disk like every other write path (SIGBUS protection).
        self.disk_full_error()?;
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
            if self.cancelled() {
                // SIGTERM mid-walk: stop at the chunk boundary; the pending
                // record stays and the next startup finishes the vanish.
                return Err(anyhow::anyhow!(
                    "NIP-62 vanish cancelled during shutdown; resuming at next startup"
                ));
            }
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
            // Test-only: fail after the in-progress record committed (the
            // caller wrote it), so the resume path runs with real crash
            // state instead of hand-written table entries.
            #[cfg(test)]
            if self
                .fail_next_vanish_chunk
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(anyhow::anyhow!("test-only vanish chunk failure"));
            }
            // A fresh write transaction per chunk: the author's history is
            // unbounded, and one transaction across it pinned the writer
            // while a MapFull aborted the whole vanish. The pending record
            // (written by the caller) makes a partial pass resumable.
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
            let mut chunk_state_removed = false;
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
                chunk_state_removed |= is_group_state_kind(event.kind);
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
            if chunk_state_removed {
                // The stamp and the state-event removals commit atomically.
                self.bump_state_stamp(&mut wtxn)?;
            }
            group_state_removed |= chunk_state_removed;
            wtxn.commit()?;
        }

        // NIP-59 gift wraps addressed to the vanished pubkey: the reserved
        // recipient index (keyed by the decoded pubkey) finds every hex case
        // variant with one narrow range. A failure here must not write the
        // marker below: the re-delivered request (or the startup resume)
        // has to finish the wraps.
        self.remove_gift_wraps_for(pubkey, &mut removed)?;

        // The completed marker and the pending clear commit together: a
        // crash between them would otherwise leave a pending record whose
        // request is already covered, and the startup resume would never
        // finish. The marker is written last, and the furthest honored
        // bound is preserved so a replay or resume never regresses it. The
        // writer thread handles one message at a time, so no put can
        // interleave between the walk and the marker: every put queued
        // behind this vanish still sees the marker (or the pending record
        // in between).
        let mut wtxn = self.env.write_txn()?;
        let covered = self.vanished_until(&wtxn, pubkey)?.unwrap_or(0);
        self.vanish
            .put(&mut wtxn, pubkey, &covered.max(until_created).to_be_bytes())?;
        self.vanish_pending.delete(&mut wtxn, pubkey)?;
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

    /// Removes every stored event whose NIP-40 expiration has arrived, then
    /// reaps `first_seen` entries older than `first_seen_min_age` seconds
    /// (0 disables the reap): once a pubkey is older than the new-pubkey
    /// gate, the entry can never reject it again, so keeping it only grows
    /// the table forever.
    ///
    /// The returned report carries the partial counters on a failed chunk
    /// (the backlog is unbounded, so a MapFull mid-pass must not hide the
    /// state events an earlier chunk already removed), and its
    /// `group_state_removed` flag reports whether a NIP-29/NIP-43 state
    /// event was among the removals so the caller rebuilds the derived
    /// state.
    pub(crate) fn purge_expired(&self, now: u64, first_seen_min_age: u64) -> RemovalReport {
        let mut removed = 0usize;
        let mut group_state_removed = false;
        let error = self
            .purge_expired_walk(now, &mut removed, &mut group_state_removed)
            .and_then(|()| self.reap_first_seen(now, first_seen_min_age))
            .err();
        RemovalReport {
            removed,
            group_state_removed,
            error,
        }
    }

    /// The expiry walk behind [`Self::purge_expired`]. A shutdown
    /// cancellation stops the walk cleanly at the chunk boundary (the next
    /// periodic purge resumes; NIP-40 has no pending record to keep).
    fn purge_expired_walk(
        &self,
        now: u64,
        removed: &mut usize,
        group_state_removed: &mut bool,
    ) -> Result<()> {
        self.disk_full_error()?;
        // NIP-40 disabled: nothing is expired. Stale entries written while
        // it was enabled are removed by `remove_event` (which deletes the
        // entry regardless of the toggle), so re-enabling the feature can
        // never resurrect a purged event through a stale key.
        if !self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        let since_key = created_key(0, &[0u8; ID_LEN]);
        // NIP-40 semantics are `expiration <= now`: include every key at the
        // current second by using the largest possible event id as the
        // inclusive upper bound.
        let until_key = created_key(now, &[0xff; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                break;
            }
            // Test-only: fail before the nth chunk, i.e. after the first
            // committed chunk for a countdown of `2` (a middle-chunk
            // failure; see `take_chunk_fault`). Expiry has no pending
            // record: the next periodic pass resumes the backlog.
            #[cfg(test)]
            if take_chunk_fault(&self.fail_chunk_after) {
                return Err(anyhow::anyhow!("test-only removal chunk failure"));
            }
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
            let mut chunk_state_removed = false;
            for (key, id) in entries {
                if let Some(raw) = self.events.get(&wtxn, &id)? {
                    if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                        chunk_state_removed |= is_group_state_kind(event.kind);
                    }
                    self.remove_event(&mut wtxn, &id)?;
                    *removed += 1;
                } else {
                    // The event is already gone (removed outside the normal
                    // path or corrupt data): drop the orphaned expiry key
                    // too, or every purge would re-examine it forever.
                    self.expiry.delete(&mut wtxn, &key)?;
                }
            }
            if chunk_state_removed {
                // The stamp and the state-event removals commit atomically
                // (a separate bump transaction would let a crash lose the
                // fact that the derived state changed).
                self.bump_state_stamp(&mut wtxn)?;
            }
            wtxn.commit()?;
            *group_state_removed |= chunk_state_removed;
        }
        Ok(())
    }

    /// Reaps `first_seen` entries whose timestamp is older than `min_age`
    /// seconds (see [`Self::purge_expired`]). `0` disables the reap. The
    /// walk is chunked so a table with millions of accounts never pins one
    /// write transaction, and a shutdown cancellation stops at the chunk
    /// boundary (the next periodic purge finishes the reap).
    fn reap_first_seen(&self, now: u64, min_age: u64) -> Result<()> {
        if min_age == 0 {
            return Ok(());
        }
        let cutoff = now.saturating_sub(min_age);
        let mut last: Option<Vec<u8>> = None;
        loop {
            if self.cancelled() {
                break;
            }
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last {
                Some(key) => std::ops::Bound::Excluded(key.as_slice()),
                None => std::ops::Bound::Unbounded,
            };
            let mut doomed: Vec<Vec<u8>> = Vec::new();
            let mut scanned = 0usize;
            let mut last_scanned: Option<Vec<u8>> = None;
            for item in self
                .first_seen
                .range(&wtxn, &(lower, std::ops::Bound::Unbounded))?
            {
                let (key, raw) = item?;
                scanned += 1;
                last_scanned = Some(key.to_vec());
                // A corrupt short entry has no usable timestamp: treat it as
                // ancient (it can never satisfy the gate) and reap it.
                let ts = raw
                    .get(..8)
                    .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
                    .unwrap_or(0);
                if ts < cutoff {
                    doomed.push(key.to_vec());
                }
                if scanned == REMOVAL_CHUNK {
                    break;
                }
            }
            for key in &doomed {
                self.first_seen.delete(&mut wtxn, key)?;
            }
            wtxn.commit()?;
            if scanned < REMOVAL_CHUNK {
                break;
            }
            last = last_scanned;
        }
        Ok(())
    }
}
